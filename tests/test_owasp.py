import pytest
from alavitrace.core.models import (
    Target,
    Host,
    Service,
    ScanResult,
    HttpResult,
    Finding,
    Severity,
    Confidence
)
from alavitrace.assessment.models import (
    OwaspCategory,
    DetectionType,
    AssessmentContext,
    OWASPFinding
)
from alavitrace.assessment.engine import AssessmentEngine
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
    detect_cookie_security,
    run_all_owasp_detectors
)

@pytest.fixture
def mock_web_context():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    host = Host(
        target=target,
        ipv4="192.168.56.106",
        open_ports=[Service(port=80, protocol="tcp", state="open", name="http")]
    )
    scan_result = ScanResult(target=target, hosts=[host])
    http_result = HttpResult(
        url="http://192.168.56.106",
        status_code=200,
        final_url="http://192.168.56.106/",
        server_header="Apache/2.4.38 (Debian)",
        missing_security_headers=["Content-Security-Policy", "X-Content-Type-Options"],
        body_sample="<html><head><title>Index of /</title></head><body><h1>Directory listing for /</h1></body></html>"
    )
    return AssessmentContext(
        target=target,
        scan_result=scan_result,
        http_results=[http_result]
    )

def test_detect_broken_access_control(mock_web_context):
    findings = detect_broken_access_control(mock_web_context)
    assert len(findings) >= 1
    dirlist_finding = next((f for f in findings if "Directory Listing" in f.title), None)
    assert dirlist_finding is not None
    assert dirlist_finding.owasp_category == OwaspCategory.A01_2021.value
    assert dirlist_finding.severity == Severity.MEDIUM
    assert dirlist_finding.confidence == Confidence.OBSERVED
    assert "Directory browsing" in dirlist_finding.description or "directory browsing" in dirlist_finding.description.lower()
    assert dirlist_finding.limitations != ""

def test_detect_broken_access_control_sensitive_path():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(
        url="http://192.168.56.106/admin",
        status_code=200,
        final_url="http://192.168.56.106/admin/login",
        redirect_chain=["http://192.168.56.106/admin"]
    )
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    findings = detect_broken_access_control(context)
    assert any("/admin" in f.title for f in findings)

def test_detect_cryptographic_failures_cleartext(mock_web_context):
    findings = detect_cryptographic_failures(mock_web_context)
    cleartext_finding = next((f for f in findings if "Cleartext HTTP" in f.title), None)
    assert cleartext_finding is not None
    assert cleartext_finding.severity == Severity.MEDIUM
    assert cleartext_finding.confidence == Confidence.CONFIRMED
    assert cleartext_finding.owasp_category == OwaspCategory.A02_2021.value
    assert "Enforce TLS" in cleartext_finding.recommendation

def test_detect_cryptographic_failures_https_hsts():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(
        url="https://192.168.56.106",
        status_code=200,
        missing_security_headers=["Strict-Transport-Security"]
    )
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    findings = detect_cryptographic_failures(context)
    hsts_finding = next((f for f in findings if "Strict-Transport-Security" in f.title), None)
    assert hsts_finding is not None
    assert hsts_finding.severity == Severity.LOW

def test_detect_injection_indicators():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(
        url="http://192.168.56.106/search",
        status_code=200,
        observed_parameters=["q", "category", "sort"]
    )
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    findings = detect_injection_indicators(context)
    assert len(findings) == 1
    assert "Observed Input Parameters" in findings[0].title
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.POTENTIAL
    assert "category, q, sort" in findings[0].parameter

def test_detect_insecure_design(mock_web_context):
    findings = detect_insecure_design(mock_web_context)
    assert len(findings) == 1
    assert "Insecure Design Assessment Limitation" in findings[0].title
    assert findings[0].severity == Severity.INFO
    assert findings[0].confidence == Confidence.INFORMATIONAL
    assert findings[0].owasp_category == OwaspCategory.A04_2021.value

def test_detect_security_misconfiguration(mock_web_context):
    findings = detect_security_misconfiguration(mock_web_context)
    titles = [f.title for f in findings]
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("Verbose Web Server Banner" in t for t in titles)

def test_detect_vulnerable_components():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    host = Host(
        target=target,
        ipv4="192.168.56.106",
        open_ports=[Service(port=80, protocol="tcp", state="open", name="http")]
    )
    cve_finding = Finding(
        id="CVE-2021-41773",
        title="Apache HTTP Server Path Traversal (CVE-2021-41773)",
        category="Vulnerability Intelligence",
        severity=Severity.CRITICAL,
        confidence=Confidence.PROBABLE,
        description="Path traversal flaw.",
        evidence="Apache 2.4.49 detected.",
        affected_asset="http://192.168.56.106",
        affected_port=80,
        affected_service="http",
        product="Apache"
    )
    context = AssessmentContext(
        target=target,
        scan_result=ScanResult(target=target, hosts=[host]),
        http_results=[HttpResult(url="http://192.168.56.106", status_code=200)],
        existing_findings=[cve_finding]
    )
    findings = detect_vulnerable_components(context)
    assert len(findings) == 1
    assert "Outdated Component" in findings[0].title
    assert findings[0].owasp_category == OwaspCategory.A06_2021.value
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].detection_type == "correlated"

def test_detect_authentication_weaknesses():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(
        url="http://192.168.56.106/login",
        status_code=200,
        forms=[{
            "action": "http://192.168.56.106/login",
            "method": "POST",
            "has_password": True,
            "inputs": [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}]
        }],
        cookies=[{"name": "session_id", "value": "xyz123", "secure": False, "httponly": False, "samesite": None}]
    )
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    findings = detect_identification_authentication_weakness(context)
    titles = [f.title for f in findings]
    assert any("Login Over HTTP" in t for t in titles)
    assert any("Missing HttpOnly" in t for t in titles)

def test_detect_software_data_integrity():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(
        url="https://192.168.56.106",
        status_code=200,
        insecure_resources=[
            "External script missing SRI: https://cdn.example.com/app.js",
            "Mixed Content script: http://insecure.example.com/tracker.js"
        ]
    )
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    findings = detect_software_data_integrity_failures(context)
    assert len(findings) == 2
    assert any("Subresource Integrity" in f.title for f in findings)
    assert any("Mixed Content" in f.title for f in findings)

def test_detect_security_logging_monitoring():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(url="http://192.168.56.106", status_code=200)
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    findings = detect_security_logging_monitoring_gaps(context)
    assert len(findings) == 1
    assert "Security Logging and Monitoring Gap" in findings[0].title
    assert findings[0].severity == Severity.INFO
    assert findings[0].owasp_category == OwaspCategory.A09_2021.value

def test_detect_ssrf_indicators():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(
        url="http://192.168.56.106/webhook",
        status_code=200,
        observed_parameters=["url", "callback", "webhook"]
    )
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    findings = detect_ssrf_indicators(context)
    assert len(findings) == 1
    assert "Potential SSRF Attack Surface" in findings[0].title
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.POTENTIAL
    assert findings[0].owasp_category == OwaspCategory.A10_2021.value

def test_detect_csrf_weaknesses():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(
        url="http://192.168.56.106/profile",
        status_code=200,
        forms=[
            {"action": "http://192.168.56.106/profile/update", "method": "POST", "has_csrf_token": False},
            {"action": "http://192.168.56.106/profile/safe", "method": "POST", "has_csrf_token": True},
            {"action": "http://192.168.56.106/profile/view", "method": "GET", "has_csrf_token": False}
        ]
    )
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    findings = detect_csrf_weaknesses(context)
    assert len(findings) == 1
    assert "Potential CSRF Vulnerability" in findings[0].title
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == Confidence.POTENTIAL
    assert findings[0].endpoint == "http://192.168.56.106/profile/update"

def test_detect_cookie_security():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(
        url="https://192.168.56.106",
        status_code=200,
        cookies=[
            {"name": "auth_token", "value": "abc", "secure": False, "httponly": True, "samesite": None},
            {"name": "theme", "value": "dark", "secure": True, "httponly": False, "samesite": "Lax"}
        ]
    )
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    findings = detect_cookie_security(context)
    titles = [f.title for f in findings]
    assert any("Missing Secure Flag Over HTTPS" in t for t in titles)
    assert any("Missing SameSite Protection" in t for t in titles)

def test_run_all_owasp_detectors_aggregation(mock_web_context):
    findings = run_all_owasp_detectors(mock_web_context)
    assert len(findings) >= 4
    categories = {f.owasp_category for f in findings}
    assert OwaspCategory.A01_2021.value in categories
    assert OwaspCategory.A02_2021.value in categories
    assert OwaspCategory.A05_2021.value in categories

def test_engine_executes_all_builtin_checks(mock_web_context):
    engine = AssessmentEngine()
    result = engine.execute(mock_web_context)
    assert result.is_http_available is True
    assert len(result.executed_checks) == 12
    assert "BrokenAccessControlCheck" in result.executed_checks
    assert "CryptographicFailuresCheck" in result.executed_checks
    assert "InjectionCheck" in result.executed_checks
    assert "InsecureDesignCheck" in result.executed_checks
    assert "SecurityMisconfigurationCheck" in result.executed_checks
    assert "VulnerableComponentsCheck" in result.executed_checks
    assert "AuthenticationCheck" in result.executed_checks
    assert "SoftwareIntegrityCheck" in result.executed_checks
    assert "LoggingMonitoringCheck" in result.executed_checks
    assert "SSRFCheck" in result.executed_checks
    assert "CSRFCheck" in result.executed_checks
    assert "CookieSecurityCheck" in result.executed_checks
    assert len(result.findings) >= 3

def test_empty_and_malformed_http_responses():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    # Status code is None (failed request)
    http_res = HttpResult(url="http://192.168.56.106", status_code=None, error_message="Timeout")
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    findings = run_all_owasp_detectors(context)
    assert findings == []
