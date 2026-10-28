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
from alavitrace.assessment.engine import (
    AssessmentEngine,
    generate_finding_fingerprint
)
from alavitrace.analysis.prioritization import VulnerabilityPrioritizer
from alavitrace.analysis.owasp import (
    detect_security_misconfiguration,
    detect_vulnerable_components,
    detect_cookie_security,
    detect_identification_authentication_weakness
)
from alavitrace.analysis.misconfiguration import (
    check_directory_listing,
    check_verbose_error_disclosure,
    check_debug_mode_exposure,
    check_http_methods,
    check_robots_txt,
    check_legacy_services
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def base_target():
    return Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")


# ============================================================================
# Unit Tests: Security Headers & Information Disclosure (A05)
# ============================================================================

def test_missing_security_headers_detection(base_target):
    http_res = HttpResult(
        url="http://192.168.56.106",
        status_code=200,
        missing_security_headers=[
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
    )
    context = AssessmentContext(target=base_target, scan_result=ScanResult(target=base_target), http_results=[http_res])
    findings = detect_security_misconfiguration(context)

    titles = [f.title for f in findings]
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert any("Referrer-Policy" in t for t in titles)
    assert any("Permissions-Policy" in t for t in titles)

    for f in findings:
        assert f.owasp_category == OwaspCategory.A05_2021.value
        assert f.confidence in [Confidence.CONFIRMED, Confidence.OBSERVED]


def test_verbose_server_and_framework_banners(base_target):
    http_res = HttpResult(
        url="http://192.168.56.106",
        status_code=200,
        server_header="Apache/2.4.38 (Debian)",
        powered_by_header="PHP/7.3.27",
        framework_headers={"X-AspNet-Version": "4.0.30319", "X-Generator": "Drupal 7"}
    )
    context = AssessmentContext(target=base_target, scan_result=ScanResult(target=base_target), http_results=[http_res])
    findings = detect_security_misconfiguration(context)

    banner_finding = next((f for f in findings if "Banner Information Disclosure" in f.title), None)
    assert banner_finding is not None
    assert banner_finding.owasp_category == OwaspCategory.A05_2021.value
    assert "Apache/2.4.38" in banner_finding.evidence
    assert "PHP/7.3.27" in banner_finding.evidence
    assert "X-AspNet-Version" in banner_finding.evidence
    assert banner_finding.confidence == Confidence.OBSERVED


# ============================================================================
# Unit Tests: Directory Listing Detection
# ============================================================================

def test_directory_listing_positive():
    body = "<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><hr><pre><a href='../'>../</a></pre></body></html>"
    match = check_directory_listing(body)
    assert match is not None
    assert "Index of /uploads" in match


def test_directory_listing_negative():
    body = "<html><head><title>Welcome to Example Company</title></head><body><h1>Hello World</h1></body></html>"
    assert check_directory_listing(body) is None


def test_directory_listing_finding_generation(base_target):
    http_res = HttpResult(
        url="http://192.168.56.106/files/",
        status_code=200,
        body_sample="<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1></body></html>"
    )
    context = AssessmentContext(target=base_target, scan_result=ScanResult(target=base_target), http_results=[http_res])
    findings = detect_security_misconfiguration(context)

    dir_finding = next((f for f in findings if "Directory Listing Enabled" in f.title), None)
    assert dir_finding is not None
    assert dir_finding.owasp_category == OwaspCategory.A05_2021.value
    assert dir_finding.severity == Severity.MEDIUM
    assert dir_finding.confidence == Confidence.PROBABLE


# ============================================================================
# Unit Tests: Verbose Error Message & Stack Trace Disclosure
# ============================================================================

def test_error_disclosure_python_traceback():
    body = 'Traceback (most recent call last):\n  File "app.py", line 42, in index\nZeroDivisionError: division by zero'
    result = check_verbose_error_disclosure(body, 500)
    assert result is not None
    engine, snippet = result
    assert engine == "Python"
    assert "Traceback" in snippet


def test_error_disclosure_java_stacktrace():
    body = '<html><body>Exception in thread "main" java.lang.NullPointerException\n\tat com.example.App.main(App.java:14)</body></html>'
    result = check_verbose_error_disclosure(body, 500)
    assert result is not None
    engine, snippet = result
    assert engine == "Java"
    assert "java.lang.NullPointerException" in snippet or "Exception in thread" in snippet


def test_error_disclosure_php_warning():
    body = "Warning: mysqli_connect(): (HY000/2002): Connection refused in /var/www/html/db.php on line 12"
    result = check_verbose_error_disclosure(body, 200)
    assert result is not None
    engine, snippet = result
    assert engine == "PHP"
    assert "/var/www/html/db.php" in snippet


def test_error_disclosure_generic_500_no_false_positive():
    generic_500 = "<html><head><title>500 Internal Server Error</title></head><body><h1>Internal Server Error</h1></body></html>"
    assert check_verbose_error_disclosure(generic_500, 500) is None
    assert check_verbose_error_disclosure("Internal Server Error", 500) is None


# ============================================================================
# Unit Tests: Debug Mode Exposure
# ============================================================================

def test_debug_mode_werkzeug():
    body = '<div class="debugger"><p>Werkzeug powered traceback interpreter</p></div>'
    result = check_debug_mode_exposure(body)
    assert result is not None
    fw, snippet = result
    assert fw == "Werkzeug"


def test_debug_mode_django():
    body = "<h1>DisallowedHost at /</h1><p>You're seeing this error because you have <code>DEBUG = True</code> in your settings file.</p>"
    result = check_debug_mode_exposure(body)
    assert result is not None
    fw, snippet = result
    assert fw == "Django"


def test_debug_mode_negative():
    body = "<html><body><h1>Dashboard</h1><p>System operational</p></body></html>"
    assert check_debug_mode_exposure(body) is None


# ============================================================================
# Unit Tests: HTTP Methods & TRACE Detection
# ============================================================================

def test_http_methods_trace_and_risky():
    methods = ["GET", "POST", "OPTIONS", "TRACE", "PUT", "DELETE"]
    risky, trace_enabled = check_http_methods(methods)
    assert trace_enabled is True
    assert "PUT" in risky
    assert "DELETE" in risky
    assert "GET" not in risky


def test_http_methods_safe():
    methods = ["GET", "POST", "HEAD", "OPTIONS"]
    risky, trace_enabled = check_http_methods(methods)
    assert trace_enabled is False
    assert risky == []


def test_http_methods_findings_generation(base_target):
    http_res = HttpResult(
        url="http://192.168.56.106",
        status_code=200,
        options_methods=["GET", "POST", "TRACE", "DELETE"]
    )
    context = AssessmentContext(target=base_target, scan_result=ScanResult(target=base_target), http_results=[http_res])
    findings = detect_security_misconfiguration(context)

    trace_finding = next((f for f in findings if "TRACE Method Enabled" in f.title), None)
    assert trace_finding is not None
    assert trace_finding.owasp_category == OwaspCategory.A05_2021.value
    assert trace_finding.confidence == Confidence.CONFIRMED

    method_finding = next((f for f in findings if "Unnecessary HTTP Method" in f.title), None)
    assert method_finding is not None
    assert "DELETE" in method_finding.evidence


# ============================================================================
# Unit Tests: HTTPS & Certificate Configuration
# ============================================================================

def test_https_certificate_expired(base_target):
    http_res = HttpResult(
        url="https://192.168.56.106",
        status_code=200,
        tls_cert_info={"is_expired": True, "expires_at": "2024-01-01 00:00:00"}
    )
    context = AssessmentContext(target=base_target, scan_result=ScanResult(target=base_target), http_results=[http_res])
    findings = detect_security_misconfiguration(context)

    expired_finding = next((f for f in findings if "Certificate Expired" in f.title), None)
    assert expired_finding is not None
    assert expired_finding.severity == Severity.HIGH
    assert expired_finding.confidence == Confidence.CONFIRMED


def test_https_certificate_mismatch(base_target):
    http_res = HttpResult(
        url="https://192.168.56.106",
        status_code=200,
        tls_cert_info={"hostname_mismatch": True}
    )
    context = AssessmentContext(target=base_target, scan_result=ScanResult(target=base_target), http_results=[http_res])
    findings = detect_security_misconfiguration(context)

    mismatch_finding = next((f for f in findings if "Hostname Mismatch" in f.title), None)
    assert mismatch_finding is not None
    assert mismatch_finding.severity == Severity.MEDIUM
    assert mismatch_finding.confidence == Confidence.CONFIRMED


def test_http_to_https_redirect_missing(base_target):
    http_res = HttpResult(
        url="http://192.168.56.106",
        status_code=200,
        final_url="http://192.168.56.106/"
    )
    https_res = HttpResult(
        url="https://192.168.56.106",
        status_code=200,
        final_url="https://192.168.56.106/"
    )
    context = AssessmentContext(target=base_target, scan_result=ScanResult(target=base_target), http_results=[http_res, https_res])
    findings = detect_security_misconfiguration(context)

    noredirect_finding = next((f for f in findings if "Does Not Enforce HTTPS Redirection" in f.title), None)
    assert noredirect_finding is not None
    assert noredirect_finding.severity == Severity.LOW


# ============================================================================
# Unit Tests: Cookie Security Attributes
# ============================================================================

def test_cookie_security_attributes(base_target):
    http_res = HttpResult(
        url="https://192.168.56.106",
        status_code=200,
        cookies=[
            {"name": "session_id", "secure": False, "httponly": False, "samesite": None}
        ]
    )
    context = AssessmentContext(target=base_target, scan_result=ScanResult(target=base_target), http_results=[http_res])

    # Cookie security checks
    cookie_findings = detect_cookie_security(context)
    auth_findings = detect_identification_authentication_weakness(context)

    secure_f = next((f for f in cookie_findings if "Missing Secure Flag" in f.title), None)
    assert secure_f is not None
    assert secure_f.owasp_category == OwaspCategory.A05_2021.value

    samesite_f = next((f for f in cookie_findings if "Missing SameSite" in f.title), None)
    assert samesite_f is not None
    assert samesite_f.owasp_category == OwaspCategory.A05_2021.value

    httponly_f = next((f for f in auth_findings if "Missing HttpOnly" in f.title), None)
    assert httponly_f is not None
    assert httponly_f.owasp_category == OwaspCategory.A07_2021.value


# ============================================================================
# Unit Tests: Robots.txt Disallow Directives
# ============================================================================

def test_robots_txt_sensitive_parsing():
    content = """User-agent: *
Disallow: /admin
Disallow: /private/data
Disallow: /images/
"""
    sensitive = check_robots_txt(content)
    assert "/admin" in sensitive
    assert "/private/data" in sensitive
    assert "/images/" not in sensitive


def test_robots_txt_finding_generation(base_target):
    http_res = HttpResult(
        url="http://192.168.56.106",
        status_code=200,
        robots_txt_disallowed=["/admin", "/backup"]
    )
    context = AssessmentContext(target=base_target, scan_result=ScanResult(target=base_target), http_results=[http_res])
    findings = detect_security_misconfiguration(context)

    robots_finding = next((f for f in findings if "Robots.txt Discloses" in f.title), None)
    assert robots_finding is not None
    assert robots_finding.owasp_category == OwaspCategory.A05_2021.value
    assert "/admin" in robots_finding.evidence


# ============================================================================
# Unit Tests: Legacy / Unnecessary Exposed Services (A05)
# ============================================================================

def test_check_legacy_services_ftp_telnet(base_target):
    host = Host(
        target=base_target,
        ipv4="192.168.56.106",
        open_ports=[
            Service(port=21, protocol="tcp", state="open", name="ftp", product="vsftpd", version="3.0.3"),
            Service(port=23, protocol="tcp", state="open", name="telnet"),
            Service(port=80, protocol="tcp", state="open", name="http")
        ]
    )
    scan_result = ScanResult(target=base_target, hosts=[host])
    findings = check_legacy_services(scan_result)

    assert len(findings) == 2
    titles = [f.title for f in findings]
    assert any("FTP" in t for t in titles)
    assert any("Telnet" in t for t in titles)
    assert not any("HTTP" in t for t in titles)

    for f in findings:
        assert f.owasp_category == OwaspCategory.A05_2021.value
        assert f.confidence == Confidence.OBSERVED
        assert f.affected_port in [21, 23]


# ============================================================================
# Unit Tests: Outdated & Vulnerable Components (A06)
# ============================================================================

def test_detect_vulnerable_components_across_all_services(base_target):
    cve_finding = Finding(
        id="FIND-VULN-1",
        title="CVE-2019-6111 in OpenSSH",
        category="Vulnerability Intelligence",
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description="OpenSSH through 7.9 scp client allows command injection.",
        evidence="CPE match: cpe:2.3:a:openbsd:openssh:7.9p1 matched CVE-2019-6111 (CVSS 5.8 MEDIUM)",
        affected_asset="192.168.56.106",
        affected_port=22,
        affected_service="ssh",
        product="OpenSSH",
        version="7.9p1",
        recommendation="Upgrade to OpenSSH 8.0 or later.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-6111"],
        source="NVD API v2 (CPE)"
    )
    context = AssessmentContext(
        target=base_target,
        scan_result=ScanResult(target=base_target),
        http_results=[],
        existing_findings=[cve_finding]
    )
    a06_findings = detect_vulnerable_components(context)

    assert len(a06_findings) == 1
    f = a06_findings[0]
    assert f.owasp_category == OwaspCategory.A06_2021.value
    assert "OpenSSH" in f.title
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.PROBABLE
    assert f.detection_type == DetectionType.CORRELATED.value
    assert "CVE-2019-6111" in f.evidence
    assert f.limitations != ""


# ============================================================================
# Unit Tests: Deduplication Prevention Between Phase 3 and OWASP A05/A06
# ============================================================================

def test_unified_fingerprint_deduplication(base_target):
    # Create a Phase 3 recommendation finding and an identical OWASP A05 finding
    finding_phase3 = Finding(
        id="REC-HTTP-HEADER-1",
        title="Missing Content-Security-Policy (CSP) Header",
        category="Security Misconfiguration",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        description="Missing CSP header.",
        evidence="Content-Security-Policy header was absent.",
        affected_asset="http://192.168.56.106",
        endpoint="http://192.168.56.106/"
    )
    finding_owasp = Finding(
        id="OWASP-A05-HEADER-CSP-1",
        title="Missing Content-Security-Policy (CSP) Header",
        category="OWASP Top 10",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        description="Missing CSP header in response.",
        evidence="Content-Security-Policy header was absent.",
        affected_asset="http://192.168.56.106",
        endpoint="http://192.168.56.106/"
    )

    # Both findings should generate identical fingerprints
    fp1 = generate_finding_fingerprint(finding_phase3)
    fp2 = generate_finding_fingerprint(finding_owasp)
    assert fp1 == fp2

    # VulnerabilityPrioritizer should deduplicate them
    engine = VulnerabilityPrioritizer()
    result = engine.prioritize([finding_phase3, finding_owasp], max_findings=10)

    # Non-vuln findings deduplicated by fingerprint
    matching_findings = [f for f in result.prioritized_findings if "Content-Security-Policy" in f.title]
    assert len(matching_findings) == 1
