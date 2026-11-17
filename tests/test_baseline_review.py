import json
import os
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
    AssessmentContext,
    AssessmentResult,
    OWASPFinding,
    OwaspCategory
)
from alavitrace.analysis.prioritization import VulnerabilityPrioritizer
from alavitrace.analysis.owasp import (
    detect_broken_access_control,
    detect_cryptographic_failures,
    detect_ssrf_indicators
)
from alavitrace.assessment.coverage import (
    OWASP_TAXONOMY_DEFINITIONS,
    get_owasp_coverage_summary
)
from alavitrace.reporting.json_report import generate_json_report
from alavitrace.reporting.markdown_report import generate_markdown_report
from alavitrace.reporting.html_report import generate_html_report


@pytest.fixture
def juice_shop_baseline_data():
    """
    Replicates the exact Juice Shop baseline assessment data:
    Target: 192.168.56.103
    Services: 22/SSH, 80/HTTP, 3000/HTTP
    2 active HTTP endpoints evaluated.
    """
    target = Target(raw_input="192.168.56.103", normalized="192.168.56.103", target_type="IPv4")
    host = Host(
        target=target,
        ipv4="192.168.56.103",
        state="up",
        open_ports=[
            Service(port=22, protocol="tcp", state="open", name="SSH", product="OpenSSH", version="10.2p1"),
            Service(port=80, protocol="tcp", state="open", name="HTTP", product="Gophish httpd"),
            Service(port=3000, protocol="tcp", state="open", name="HTTP", product="Node.js Express")
        ]
    )
    scan_result = ScanResult(target=target, hosts=[host])

    http_results = [
        HttpResult(
            url="http://192.168.56.103",
            final_url="http://192.168.56.103/",
            status_code=404,
            response_time_ms=6.1,
            server_header="Gophish",
            missing_security_headers=[
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy"
            ],
            forms=[]
        ),
        HttpResult(
            url="http://192.168.56.103:3000",
            final_url="http://192.168.56.103:3000/",
            status_code=200,
            response_time_ms=15.4,
            server_header="Express",
            missing_security_headers=[
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "Referrer-Policy",
                "Permissions-Policy"
            ],
            forms=[]
        )
    ]

    # 7 passive security header observations
    header_findings = [
        Finding(
            id="FIND-SEC-HEADER-CSP-1",
            title="Missing Content-Security-Policy (CSP) Header",
            category="Web Security Configuration",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            description="Missing CSP header.",
            evidence="Header 'Content-Security-Policy' was missing at http://192.168.56.103.",
            affected_asset="http://192.168.56.103",
            recommendation="Implement CSP.",
            source="AlaviTrace Security Header Rules",
            owasp_category="A05:2021 - Security Misconfiguration"
        ),
        Finding(
            id="FIND-SEC-HEADER-XFO-1",
            title="Missing X-Frame-Options Header",
            category="Web Security Configuration",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            description="Missing XFO header.",
            evidence="Header 'X-Frame-Options' was missing at http://192.168.56.103.",
            affected_asset="http://192.168.56.103",
            recommendation="Implement XFO.",
            source="AlaviTrace Security Header Rules",
            owasp_category="A05:2021 - Security Misconfiguration"
        ),
        Finding(
            id="FIND-SEC-HEADER-RP-1",
            title="Missing Referrer-Policy Header",
            category="Web Security Configuration",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            description="Missing Referrer-Policy header.",
            evidence="Header 'Referrer-Policy' was missing at http://192.168.56.103.",
            affected_asset="http://192.168.56.103",
            recommendation="Implement Referrer-Policy.",
            source="AlaviTrace Security Header Rules",
            owasp_category="A05:2021 - Security Misconfiguration"
        ),
        Finding(
            id="FIND-SEC-HEADER-PP-1",
            title="Missing Permissions-Policy Header",
            category="Web Security Configuration",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            description="Missing Permissions-Policy header.",
            evidence="Header 'Permissions-Policy' was missing at http://192.168.56.103.",
            affected_asset="http://192.168.56.103",
            recommendation="Implement Permissions-Policy.",
            source="AlaviTrace Security Header Rules",
            owasp_category="A05:2021 - Security Misconfiguration"
        ),
        Finding(
            id="FIND-SEC-HEADER-CSP-2",
            title="Missing Content-Security-Policy (CSP) Header",
            category="Web Security Configuration",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            description="Missing CSP header.",
            evidence="Header 'Content-Security-Policy' was missing at http://192.168.56.103:3000.",
            affected_asset="http://192.168.56.103:3000",
            recommendation="Implement CSP.",
            source="AlaviTrace Security Header Rules",
            owasp_category="A05:2021 - Security Misconfiguration"
        ),
        Finding(
            id="FIND-SEC-HEADER-RP-2",
            title="Missing Referrer-Policy Header",
            category="Web Security Configuration",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            description="Missing Referrer-Policy header.",
            evidence="Header 'Referrer-Policy' was missing at http://192.168.56.103:3000.",
            affected_asset="http://192.168.56.103:3000",
            recommendation="Implement Referrer-Policy.",
            source="AlaviTrace Security Header Rules",
            owasp_category="A05:2021 - Security Misconfiguration"
        ),
        Finding(
            id="FIND-SEC-HEADER-PP-2",
            title="Missing Permissions-Policy Header",
            category="Web Security Configuration",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            description="Missing Permissions-Policy header.",
            evidence="Header 'Permissions-Policy' was missing at http://192.168.56.103:3000.",
            affected_asset="http://192.168.56.103:3000",
            recommendation="Implement Permissions-Policy.",
            source="AlaviTrace Security Header Rules",
            owasp_category="A05:2021 - Security Misconfiguration"
        )
    ]

    # 4 OWASP application findings
    app_findings = [
        OWASPFinding.create(
            id="OWASP-A02-CLEARTEXT-1",
            title="Cleartext HTTP Service Without Enforced HTTPS",
            owasp_category="A02:2021 - Cryptographic Failures",
            severity=Severity.LOW,
            confidence=Confidence.OBSERVED,
            description="Unencrypted HTTP service without redirection to HTTPS.",
            evidence="Endpoint http://192.168.56.103 responded over cleartext HTTP with status 404 without redirecting to HTTPS.",
            affected_asset="http://192.168.56.103",
            endpoint="http://192.168.56.103/",
            source="AlaviTrace OWASP Engine"
        ),
        OWASPFinding.create(
            id="OWASP-A02-CLEARTEXT-2",
            title="Cleartext HTTP Service Without Enforced HTTPS",
            owasp_category="A02:2021 - Cryptographic Failures",
            severity=Severity.LOW,
            confidence=Confidence.OBSERVED,
            description="Unencrypted HTTP service without redirection to HTTPS.",
            evidence="Endpoint http://192.168.56.103:3000 responded over cleartext HTTP with status 200 without redirecting to HTTPS.",
            affected_asset="http://192.168.56.103:3000",
            endpoint="http://192.168.56.103:3000/",
            source="AlaviTrace OWASP Engine"
        ),
        OWASPFinding.create(
            id="OWASP-A04-DESIGN-NOTE-1",
            title="Insecure Design Assessment Limitation",
            owasp_category="A04:2021 - Insecure Design",
            severity=Severity.INFO,
            confidence=Confidence.INFORMATIONAL,
            description="External reconnaissance cannot evaluate threat models or business logic architecture.",
            evidence="External reconnaissance cannot evaluate threat models.",
            affected_asset="http://192.168.56.103",
            endpoint="http://192.168.56.103",
            source="AlaviTrace OWASP Engine"
        ),
        OWASPFinding.create(
            id="OWASP-A09-LOGGING-NOTE-1",
            title="Security Logging and Monitoring Gap (Assessment Limitation)",
            owasp_category="A09:2021 - Security Logging and Monitoring Failures",
            severity=Severity.INFO,
            confidence=Confidence.INFORMATIONAL,
            description="External reconnaissance cannot evaluate centralized logging.",
            evidence="External reconnaissance cannot evaluate logging pipeline.",
            affected_asset="http://192.168.56.103",
            endpoint="http://192.168.56.103",
            source="AlaviTrace OWASP Engine"
        )
    ]

    all_findings = header_findings + app_findings
    prioritization_result = VulnerabilityPrioritizer().prioritize(all_findings, max_findings=20)

    owasp_result = AssessmentResult(
        is_http_available=True,
        findings=app_findings,
        executed_checks=["CryptographicFailuresCheck", "InsecureDesignCheck", "LoggingMonitoringCheck"],
        supported_categories=["A02:2021", "A05:2021"]
    )

    return scan_result, http_results, prioritization_result, owasp_result


def test_endpoint_and_form_accounting_with_null_attack_surface(tmp_path, juice_shop_baseline_data):
    """
    Verifies that when attack_surface is None:
    1. total_endpoints reflects the 2 genuine discovered HTTP endpoints.
    2. total_forms is 0 (not invented).
    3. attack_surface is null in JSON without crashing.
    4. Markdown and HTML reports handle null attack_surface honestly.
    """
    scan_result, http_results, prioritization_result, owasp_result = juice_shop_baseline_data

    # Generate JSON Report with attack_surface=None
    json_path = generate_json_report(
        scan_result=scan_result,
        http_results=http_results,
        prioritization_result=prioritization_result,
        ai_analysis=None,
        output_dir=str(tmp_path),
        owasp_result=owasp_result,
        attack_surface=None
    )

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 1. Endpoint accounting
    assert data["summary"]["total_endpoints"] == 2
    assert data["summary"]["total_forms"] == 0
    assert data["summary"]["total_services"] == 3
    assert data["attack_surface"] is None

    # Attack surface score: 3 services * 5.0 + 2 endpoints * 2.0 + 0 forms * 3.0 = 19.0
    assert data["summary"]["attack_surface_score"] == 19.0

    # 2. Markdown Report
    md_path = generate_markdown_report(
        scan_result=scan_result,
        http_results=http_results,
        prioritization_result=prioritization_result,
        ai_analysis=None,
        output_dir=str(tmp_path),
        owasp_result=owasp_result,
        attack_surface=None
    )

    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    assert "| **Discovered Web Endpoints** | 2 |" in md_text
    assert "Attack surface mapping was not executed for this assessment" in md_text
    assert "Passive HTTP enumeration evaluated 2 endpoint(s)" in md_text

    # 3. HTML Report
    html_path = generate_html_report(
        scan_result=scan_result,
        http_results=http_results,
        prioritization_result=prioritization_result,
        ai_analysis=None,
        output_dir=str(tmp_path),
        owasp_result=owasp_result,
        attack_surface=None
    )

    with open(html_path, "r", encoding="utf-8") as f:
        html_text = f.read()

    assert "Attack surface mapping was not executed for this assessment" in html_text
    assert "Passive HTTP enumeration evaluated 2 endpoint(s)" in html_text


def test_form_accounting_positive_when_forms_discovered(tmp_path, juice_shop_baseline_data):
    """
    Verifies that form accounting detects actual forms from http_results without inventing counts.
    """
    scan_result, http_results, prioritization_result, owasp_result = juice_shop_baseline_data

    # Add a genuine discovered form to one of the HTTP results
    http_results[0].forms = [
        {"action": "/feedback", "method": "POST", "inputs": [{"name": "comment"}]}
    ]

    json_path = generate_json_report(
        scan_result=scan_result,
        http_results=http_results,
        prioritization_result=prioritization_result,
        ai_analysis=None,
        output_dir=str(tmp_path),
        owasp_result=owasp_result,
        attack_surface=None
    )

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["summary"]["total_forms"] == 1
    # 3 services * 5.0 + 2 endpoints * 2.0 + 1 form * 3.0 = 22.0
    assert data["summary"]["attack_surface_score"] == 22.0


def test_owasp_coverage_accuracy_and_honest_taxonomy():
    """
    Verifies that OWASP coverage matrix and taxonomy definitions clearly distinguish:
    - heuristic indicators / candidate findings from validated vulnerabilities
    - sensitive path discovery != broken access control
    - reflected canary != exploitable XSS
    - parameter discovery != SSRF
    """
    # A01
    a01 = OWASP_TAXONOMY_DEFINITIONS["A01:2021"]
    assert any("candidate access-control indicators" in c for c in a01["capabilities"])
    assert any("does not prove authorization bypass" in lim for lim in a01["limitations"])

    # A02
    a02 = OWASP_TAXONOMY_DEFINITIONS["A02:2021"]
    assert any("Cleartext HTTP transport detection" in c for c in a02["capabilities"])
    assert any("does not assume confidential data exposure" in lim for lim in a02["limitations"])

    # A03
    a03 = OWASP_TAXONOMY_DEFINITIONS["A03:2021"]
    assert any("not proof of exploitable XSS" in c for c in a03["capabilities"])
    assert any("do not confirm executable cross-site scripting" in lim for lim in a03["limitations"])

    # A10
    a10 = OWASP_TAXONOMY_DEFINITIONS["A10:2021"]
    assert any("candidate SSRF attack surface" in c for c in a10["capabilities"])
    assert any("does not prove server-side request execution" in lim for lim in a10["limitations"])

    # Summary notes
    cov = get_owasp_coverage_summary([])
    assert any("Heuristic observations" in note for note in cov.summary_notes)


def test_cleartext_http_classification_benign_vs_sensitive():
    """
    Verifies that cleartext HTTP findings do not overstate impact:
    - Benign endpoint without credentials -> Severity.LOW
    - Endpoint with password form or auth path -> Severity.MEDIUM
    """
    target = Target(raw_input="192.168.56.103", normalized="192.168.56.103", target_type="IPv4")

    # 1. Benign cleartext HTTP endpoint
    benign_res = HttpResult(
        url="http://192.168.56.103",
        status_code=404,
        forms=[]
    )
    benign_context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[benign_res])
    findings = detect_cryptographic_failures(benign_context)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == Confidence.OBSERVED
    assert "Without Enforced HTTPS" in findings[0].title
    assert "No sensitive input forms" in findings[0].evidence

    # 2. Cleartext HTTP endpoint with password form
    sensitive_form_res = HttpResult(
        url="http://192.168.56.103:3000",
        status_code=200,
        forms=[{"action": "/rest/user/login", "method": "POST", "has_password": True}]
    )
    sens_context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[sensitive_form_res])
    sens_findings = detect_cryptographic_failures(sens_context)
    assert len(sens_findings) == 1
    assert sens_findings[0].severity == Severity.MEDIUM
    assert sens_findings[0].confidence == Confidence.CONFIRMED
    assert "Sensitive Information" in sens_findings[0].title

    # 3. Cleartext HTTP endpoint with login path
    login_path_res = HttpResult(
        url="http://192.168.56.103/login",
        status_code=200,
        forms=[]
    )
    login_context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[login_path_res])
    login_findings = detect_cryptographic_failures(login_context)
    assert len(login_findings) == 1
    assert login_findings[0].severity == Severity.MEDIUM
    assert "Sensitive Information" in login_findings[0].title


def test_finding_deduplication_traceability_and_severity_distribution(tmp_path, juice_shop_baseline_data):
    """
    Verifies that:
    1. No finding is counted twice.
    2. Findings remain traceable to their source ("AlaviTrace Security Header Rules" vs "AlaviTrace OWASP Engine").
    3. Reports clearly distinguish security headers from application OWASP findings.
    4. Severity distribution matches actual unique finding records (5 Low, 6 Info = 11 total).
    5. A05 Misconfigurations shows 7 across summary, owasp_assessment, and coverage matrix.
    """
    scan_result, http_results, prioritization_result, owasp_result = juice_shop_baseline_data

    # 1. JSON Report
    json_path = generate_json_report(
        scan_result=scan_result,
        http_results=http_results,
        prioritization_result=prioritization_result,
        ai_analysis=None,
        output_dir=str(tmp_path),
        owasp_result=owasp_result
    )

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Top-level summary counts
    assert data["summary"]["total_findings"] == 11
    assert data["summary"]["medium_findings"] == 0
    assert data["summary"]["low_findings"] == 5
    assert data["summary"]["info_findings"] == 6

    # OWASP assessment section counts
    owasp_sec = data["owasp_assessment"]
    assert owasp_sec["findings_count"] == 11
    assert owasp_sec["application_findings_count"] == 4
    assert owasp_sec["security_header_observations_count"] == 7
    assert owasp_sec["a05_misconfiguration"]["total_count"] == 7
    assert owasp_sec["a05_misconfiguration"]["security_headers_count"] == 7
    assert owasp_sec["a05_misconfiguration"]["other_misconfigurations_count"] == 0

    # Severity distribution in owasp_assessment matches unique findings
    assert owasp_sec["summary_by_severity"]["medium"] == 0
    assert owasp_sec["summary_by_severity"]["low"] == 5
    assert owasp_sec["summary_by_severity"]["informational"] == 6

    # Coverage matrix matches
    assert data["owasp_coverage"]["categories"]["A05:2021"]["findings_count"] == 7
    assert data["owasp_coverage"]["categories"]["A02:2021"]["findings_count"] == 2

    # Verify traceability to source
    sources = set(f["source"] for f in owasp_sec["findings"])
    assert "AlaviTrace Security Header Rules" in sources
    assert "AlaviTrace OWASP Engine" in sources

    # Verify no duplicate finding IDs
    finding_ids = [f["id"] for f in data["all_findings"]]
    assert len(finding_ids) == len(set(finding_ids)) == 11

    # 2. Markdown Report
    md_path = generate_markdown_report(
        scan_result=scan_result,
        http_results=http_results,
        prioritization_result=prioritization_result,
        ai_analysis=None,
        output_dir=str(tmp_path),
        owasp_result=owasp_result
    )

    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    assert "Total Findings:** 11" in md_text
    assert "### Application Security Findings (4)" in md_text
    assert "### Passive Security Header Observations (7 A05 Misconfigurations)" in md_text
    assert "- **Total Security Misconfigurations:** 7" in md_text

    # 3. HTML Report
    html_path = generate_html_report(
        scan_result=scan_result,
        http_results=http_results,
        prioritization_result=prioritization_result,
        ai_analysis=None,
        output_dir=str(tmp_path),
        owasp_result=owasp_result
    )

    with open(html_path, "r", encoding="utf-8") as f:
        html_text = f.read()

    assert "A05 Misconfigurations: <strong>7</strong>" in html_text
    assert "Low: 5" in html_text
    assert "Info: 6" in html_text
    assert "Medium: 0" in html_text


def test_sensitive_path_and_ssrf_honest_candidate_reporting():
    """
    Verifies that A01 sensitive path discovery and A10 parameter discovery
    report candidate indicators with honest limitations rather than claiming confirmed exploits.
    """
    target = Target(raw_input="192.168.56.103", normalized="192.168.56.103", target_type="IPv4")

    # A01 sensitive path
    admin_res = HttpResult(
        url="http://192.168.56.103/admin",
        status_code=200
    )
    a01_ctx = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[admin_res])
    a01_findings = detect_broken_access_control(a01_ctx)
    path_finding = next((f for f in a01_findings if "Sensitive Path" in f.title), None)
    assert path_finding is not None
    assert path_finding.severity == Severity.LOW
    assert "Candidate Access Control Indicator" in path_finding.title
    assert "authentication bypass" in path_finding.limitations

    # A10 candidate parameter
    ssrf_res = HttpResult(
        url="http://192.168.56.103/fetch",
        status_code=200,
        observed_parameters=["url", "target"]
    )
    a10_ctx = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[ssrf_res])
    a10_findings = detect_ssrf_indicators(a10_ctx)
    assert len(a10_findings) == 1
    assert a10_findings[0].severity == Severity.LOW
    assert "Candidate Parameter" in a10_findings[0].title
    assert "does NOT prove server-side request forgery" in a10_findings[0].description
    assert "Parameter discovery identifies candidate inputs" in a10_findings[0].limitations
